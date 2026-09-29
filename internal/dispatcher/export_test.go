package dispatcher

// Hooks lets the tests hold a tick at a point, to overlap two ticks or a tick and a runner
// deterministically. Only tests can set them: this file is compiled only into the test binary.
type Hooks = hooks

// SetHooks installs hooks on a dispatcher.
func SetHooks(d *Dispatcher, h Hooks) { d.hooks = h }

// SetLockTimeout changes how long a tick's transaction waits for any lock.
func SetLockTimeout(d *Dispatcher, ms int) { d.lockTimeoutMS = ms }
