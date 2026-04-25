module.exports = {
  apps: [
    {
      name: "outbound-call-agent",
      script: "venv/bin/python",
      args: "agent.py start",
      cwd: "/home/dvolkov/outbound-call-agent",
      instances: 1,
      exec_mode: "fork",
      env: {
        PYTHONUNBUFFERED: "1",
      },
      max_memory_restart: "800M",
      autorestart: true,
      max_restarts: 10,
      min_uptime: "30s",
    },
  ],
};
