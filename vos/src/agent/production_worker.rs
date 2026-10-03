//! Exclusive lifecycle/reconciliation owner outside the node routing loop.
//!
//! This does not relax inventory freshness or parallelize ordered management.
//! One worker owns the entire semantic pipeline; serving uses published handles.

use std::sync::{
    Arc, Mutex, RwLock,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::local_lifecycle::{LocalLifecycleQueue, PendingLocalLifecycle};
use super::production_owner::{
    AgentProductionOwner, AgentProductionOwnerError as Error, CleanAgentIngress,
};
use super::supervisor::AgentSupervisorHandle;

type Operation = Box<dyn FnOnce(Option<&mut AgentProductionOwner>) + Send>;

struct Command(Option<Operation>);

impl Command {
    fn run(mut self, owner: Option<&mut AgentProductionOwner>) {
        self.0.take().expect("control command executes once")(owner);
    }
}

impl Drop for Command {
    fn drop(&mut self) {
        // Also covers a send racing receiver teardown after its explicit drain.
        if let Some(operation) = self.0.take() {
            operation(None);
        }
    }
}

struct Control {
    shutdown: Arc<AtomicBool>,
    supervisor: AgentSupervisorHandle,
    exposed: Arc<RwLock<Option<CleanAgentIngress>>>,
    recovering: Arc<AtomicBool>,
    lifecycle: Arc<LocalLifecycleQueue>,
    activity: Mutex<(bool, Instant)>,
}

struct ActiveWork<'a> {
    activity: &'a Mutex<(bool, Instant)>,
    touched: bool,
}

impl<'a> ActiveWork<'a> {
    fn enter(activity: &'a Mutex<(bool, Instant)>) -> Self {
        activity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .0 = true;
        Self {
            activity,
            touched: true,
        }
    }
}

impl Drop for ActiveWork<'_> {
    fn drop(&mut self) {
        let mut activity = self
            .activity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        activity.0 = false;
        if self.touched {
            activity.1 = Instant::now();
        }
    }
}

impl Control {
    fn stop(&self) {
        self.shutdown.store(true, Ordering::Release);
        self.lifecycle.close();
        // Cancellation never needs the busy production owner's lock.
        self.supervisor.request_shutdown();
        let mut exposed = self
            .exposed
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *exposed = None;
    }

    fn publish_recovered(&self, owner: &AgentProductionOwner) -> Result<(), Error> {
        if self.recovering.load(Ordering::Acquire) && owner.is_ready() {
            let handle = owner.ingress()?;
            let mut exposed = self
                .exposed
                .write()
                .map_err(|_| Error::InvalidConfiguration)?;
            if self.shutdown.load(Ordering::Acquire) {
                return Err(Error::ShutdownRequested);
            }
            *exposed = Some(handle);
            self.recovering.store(false, Ordering::Release);
            tracing::info!("Clean Agent recovery complete; verified routes ready");
        }
        Ok(())
    }
}

// Close admission/publication even on panic, then reject queued direct calls.
struct ExitGuard {
    control: Arc<Control>,
    commands: mpsc::Receiver<Command>,
}

impl Drop for ExitGuard {
    fn drop(&mut self) {
        self.control.stop();
        for command in self.commands.try_iter() {
            command.run(None);
        }
    }
}

pub(crate) struct AgentProductionWorker {
    control: Arc<Control>,
    commands: mpsc::SyncSender<Command>,
    join: Option<JoinHandle<Result<(), Error>>>,
}

impl AgentProductionWorker {
    pub(crate) fn start(
        mut owner: AgentProductionOwner,
        shutdown: Arc<AtomicBool>,
        exposed: Arc<RwLock<Option<CleanAgentIngress>>>,
        recovering: Arc<AtomicBool>,
        lifecycle: Arc<LocalLifecycleQueue>,
    ) -> Result<Self, Error> {
        owner.set_shutdown_signal(shutdown.clone());
        let control = Arc::new(Control {
            shutdown,
            supervisor: owner.handle(),
            exposed,
            recovering,
            lifecycle,
            activity: Mutex::new((false, Instant::now())),
        });
        // Direct embedder calls are bounded separately from HTTP lifecycle admission.
        let (commands, receiver) = mpsc::sync_channel(4);
        let worker_control = control.clone();
        let join = thread::Builder::new()
            .name("vos-agent-control".into())
            .spawn(move || {
                let guard = ExitGuard {
                    control: worker_control,
                    commands: receiver,
                };
                let result = drive(&mut owner, &guard);
                guard.control.stop();
                let shutdown = owner.shutdown_and_join();
                result.and(shutdown)
            })
            .map_err(|_| {
                control.stop();
                Error::InvalidConfiguration
            })?;
        Ok(Self {
            control,
            commands,
            join: Some(join),
        })
    }

    /// Rejected commands receive `None`, allowing transferred attachments to
    /// retire explicitly rather than losing their backend ownership on Drop.
    pub(crate) fn call<R: Send + 'static>(
        &self,
        operation: impl FnOnce(Option<&mut AgentProductionOwner>) -> R + Send + 'static,
    ) -> Result<R, Error> {
        let (reply, receiver) = mpsc::sync_channel(1);
        let command = Command(Some(Box::new(move |owner| {
            let _ = reply.try_send(operation(owner));
        })));
        if self.control.shutdown.load(Ordering::Acquire) {
            command.run(None);
            return Err(Error::ShutdownRequested);
        }
        match self.commands.try_send(command) {
            Ok(()) => receiver.recv().map_err(|_| Error::InvalidConfiguration),
            Err(mpsc::TrySendError::Full(command) | mpsc::TrySendError::Disconnected(command)) => {
                command.run(None);
                Err(Error::InvalidConfiguration)
            }
        }
    }

    pub(crate) fn is_running(&self) -> bool {
        !self.control.shutdown.load(Ordering::Acquire)
            && self.join.as_ref().is_some_and(|join| !join.is_finished())
            && self.control.supervisor.is_running()
    }

    pub(crate) fn request_shutdown(&self) {
        self.control.stop();
    }

    pub(crate) fn idle_for(&self) -> Duration {
        let activity = self
            .control
            .activity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if activity.0 {
            Duration::ZERO
        } else {
            activity.1.elapsed()
        }
    }

    pub(crate) fn shutdown_and_join(mut self) -> Result<(), Error> {
        self.request_shutdown();
        self.join
            .take()
            .ok_or(Error::InvalidConfiguration)?
            .join()
            .map_err(|_| Error::InvalidConfiguration)?
    }
}

impl Drop for AgentProductionWorker {
    fn drop(&mut self) {
        self.request_shutdown();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn drive(owner: &mut AgentProductionOwner, guard: &ExitGuard) -> Result<(), Error> {
    let control = &guard.control;
    while !control.shutdown.load(Ordering::Acquire) {
        match guard.commands.recv_timeout(Duration::from_millis(50)) {
            Ok(command) if !control.shutdown.load(Ordering::Acquire) => {
                let _active = ActiveWork::enter(&control.activity);
                command.run(Some(owner));
            }
            Ok(command) => command.run(None),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if control.shutdown.load(Ordering::Acquire) {
            break;
        }
        if let Some(request) = control
            .lifecycle
            .pop()
            .map_err(|_| Error::InvalidConfiguration)?
        {
            if control.shutdown.load(Ordering::Acquire) {
                request.reject();
                break;
            }
            let _active = ActiveWork::enter(&control.activity);
            dispatch(owner, request);
        }
        if control.shutdown.load(Ordering::Acquire) {
            break;
        }
        let reconciliation = {
            let mut active = ActiveWork::enter(&control.activity);
            let result = owner.drive_if_due(Instant::now());
            active.touched = !matches!(result, Ok(false));
            result
        };
        match reconciliation {
            Err(Error::ShutdownRequested) if control.shutdown.load(Ordering::Acquire) => break,
            result => {
                result?;
            }
        }
        match control.publish_recovered(owner) {
            Err(Error::ShutdownRequested) if control.shutdown.load(Ordering::Acquire) => break,
            result => result?,
        }
        if !owner.is_running() {
            return Err(Error::InvalidConfiguration);
        }
    }
    Ok(())
}

fn dispatch(owner: &mut AgentProductionOwner, request: PendingLocalLifecycle) {
    match request {
        PendingLocalLifecycle::PrepareAdmin { draft, reply } => {
            let _ = reply.try_send(owner.prepare_admin(&draft));
        }
        PendingLocalLifecycle::SubmitAdmin {
            call,
            preparation,
            reply,
        } => {
            let _ = reply.try_send(owner.submit_admin(&call, &preparation));
        }
        PendingLocalLifecycle::PrepareOperation { call, reply } => {
            let _ = reply.try_send(owner.prepare_operation(&call));
        }
        PendingLocalLifecycle::AuthorizeOperation { submission, reply } => {
            let (call, context, issued_at) = submission.into_parts();
            let _ = reply.try_send(owner.authorize_operation(&call, context, issued_at));
        }
        PendingLocalLifecycle::Create(request) => {
            let _ = request.reply.try_send(owner.create_local_disposition(
                request.descriptor,
                request.call,
                request.runtime,
            ));
        }
        #[cfg(all(
            target_os = "linux",
            feature = "storage",
            feature = "experimental-state-blocks"
        ))]
        PendingLocalLifecycle::CreateExternal { submission, reply } => {
            let _ = reply.try_send(owner.create_external_local_disposition(submission));
        }
        PendingLocalLifecycle::Install { submission, reply } => {
            let (install, call, package) = submission.into_parts();
            let _ = reply.try_send(owner.install_local_actor(install, call, package));
        }
        PendingLocalLifecycle::CreateShared { submission, reply } => {
            let _ = reply.try_send(owner.create_shared_agent(submission));
        }
        PendingLocalLifecycle::InstallShared { submission, reply } => {
            let _ = reply.try_send(owner.install_shared_actor(submission));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn empty_polls_do_not_reset_the_idle_clock_but_completed_work_does() {
        let old = Instant::now() - Duration::from_secs(1);
        let activity = Mutex::new((false, old));
        {
            let mut active = ActiveWork::enter(&activity);
            assert!(activity.lock().unwrap().0);
            active.touched = false;
        }
        assert_eq!(*activity.lock().unwrap(), (false, old));
        let started = Instant::now();
        drop(ActiveWork::enter(&activity));
        let completed = activity.lock().unwrap();
        assert!(!completed.0);
        assert!(completed.1 >= started);
    }

    #[test]
    fn receiver_teardown_rejects_transferred_commands_exactly_once() {
        let rejected = Arc::new(AtomicUsize::new(0));
        let (sender, receiver) = mpsc::sync_channel(1);
        let count = rejected.clone();
        sender
            .try_send(Command(Some(Box::new(move |owner| {
                assert!(owner.is_none());
                count.fetch_add(1, Ordering::SeqCst);
            }))))
            .ok()
            .unwrap();
        drop(receiver);
        assert_eq!(rejected.load(Ordering::SeqCst), 1);
        let count = rejected.clone();
        Command(Some(Box::new(move |owner| {
            assert!(owner.is_none());
            count.fetch_add(1, Ordering::SeqCst);
        })))
        .run(None);
        assert_eq!(rejected.load(Ordering::SeqCst), 2);
    }
}
