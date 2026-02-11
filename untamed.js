#!/usr/bin/env node

/**
 * UnTamed
 * Copyright (C) 2025  vestron.wtf <oss@vestron.wtf>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, version 3 of the License only.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
const net = require("net");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

const PROJECT_ROOT = __dirname;
const SERVER_PATH = path.join(PROJECT_ROOT, "server.js");
const PID_FILE = path.join(PROJECT_ROOT, ".untamed.pid");

const CONTROL_PATH = process.platform === "win32"
  ? "\\\\.\\pipe\\untamed-control"
  : "/tmp/untamed-control.sock";

const cmd = (process.argv[2] || "").toLowerCase();

function isRunning(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function readPid() {
  if (!fs.existsSync(PID_FILE)) return null;
  const pid = parseInt(fs.readFileSync(PID_FILE, "utf8"), 10);
  return isNaN(pid) ? null : pid;
}

function writePid(pid) {
  fs.writeFileSync(PID_FILE, String(pid));
}

function removePid() {
  if (fs.existsSync(PID_FILE)) fs.unlinkSync(PID_FILE);
}

function sendControl(command) {
  const client = net.createConnection(CONTROL_PATH);

  client.on("connect", () => {
    client.write(command);
  });

  client.on("data", (data) => {
    process.stdout.write(data.toString());
    client.end();
  });

  client.on("error", () => {
    console.error("Untamed is not running.");
    process.exit(1);
  });
}

//cmds (WIP!!!)
if (cmd === "start") {

  const existingPid = readPid();

  if (existingPid && isRunning(existingPid)) {
    console.log("Untamed already running (PID " + existingPid + ")");
    process.exit(0);
  }

  const child = spawn(process.execPath, [SERVER_PATH], {
    detached: true,
    stdio: "ignore"
  });

  child.unref();

  writePid(child.pid);

  console.log("Untamed started (PID " + child.pid + ")");
  process.exit(0);
}

if (cmd === "exit" || cmd === "stop") {

  sendControl("exit");

  const pid = readPid();
  if (pid) removePid();

  process.exit(0);
}

if (cmd === "regen") {
  sendControl("regen");
  process.exit(0);
}

if (cmd === "status") {

  const pid = readPid();

  if (!pid) {
    console.log("Untamed not running.");
    process.exit(0);
  }

  if (isRunning(pid)) {
    console.log("Untamed running (PID " + pid + ")");
  } else {
    console.log("Untamed not running (stale PID file)");
    removePid();
  }

  process.exit(0);
}

console.log(`
Untamed CLI

Commands:
  untamed start
  untamed exit
  untamed regen
  untamed status
`);
process.exit(0);
