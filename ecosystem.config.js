module.exports = {
  apps: [
    {
      name: "dapurkita",
      script: "server.js",
      cwd: __dirname,
      instances: 1,
      exec_mode: "fork",
      autorestart: true,
      watch: false,
      max_memory_restart: "300M",
      restart_delay: 3000,
      kill_timeout: 5000,
      time: true,
      out_file: "./logs/out.log",
      error_file: "./logs/error.log",
      merge_logs: true,
      env: {
        NODE_ENV: "production",
        HOST: "0.0.0.0",
        PORT: 3000,
      },
    },
  ],
};
