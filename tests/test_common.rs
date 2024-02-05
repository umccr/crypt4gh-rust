#![allow(clippy::missing_panics_doc)]

use std::env;
use std::ffi::OsStr;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};

pub const BOB_PASSPHRASE: &str = "bob";
pub const BOB_PUBKEY: &str = "testfiles/bob.pub";
pub const BOB_SECKEY: &str = "testfiles/bob.sec";

pub const BOB_SECKEY_SSH: &str = "bob.sshkey";
pub const BOB_PUBKEY_SSH: &str = "bob.sshkey.pub";

pub const ALICE_PASSPHRASE: &str = "alice";
pub const ALICE_PUBKEY: &str = "testfiles/alice.pub";
pub const ALICE_SECKEY: &str = "testfiles/alice.sec";

pub const ALICE_SECKEY_SSH: &str = "alice.sshkey";
pub const ALICE_PUBKEY_SSH: &str = "alice.sshkey.pub";

pub const TEMP_LOCATION: &str = "tests/tempfiles";
pub const TESTFILE_ABCD: &str = "tests/testfiles/testfile.abcd";
pub const TESTFILE_ABBBC: &str = "tests/testfiles/testfile.abbbc";

pub struct CommandUnderTest {
	raw: Command,
	stdin: Vec<u8>,
	run: bool,
	stdout: String,
	stderr: String,
}

impl CommandUnderTest {
	#[must_use]
	pub fn new() -> Self {
		// To find the directory where the built binary is, we walk up the directory tree of the test binary until the
		// parent is "target/".
		let mut binary_path = env::current_exe().expect("need current binary path to find binary to test");
		loop {
			{
				let parent = binary_path.parent();
				assert!(
					parent.is_some(),
					"Failed to locate binary path from original path: {:?}",
					env::current_exe()
				);
				let parent = parent.unwrap();
				if parent.is_dir() && parent.file_name().unwrap() == "target" {
					break;
				}
			}
			binary_path.pop();
		}

		binary_path.push(
			if cfg!(target_os = "windows") {
				format!("{}.exe", env!("CARGO_BIN_EXE_crypt4gh"))
			}
			else {
				env!("CARGO_BIN_EXE_crypt4gh").to_string()
			},
		);

		let mut cmd = Command::new(binary_path);

		let mut work_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
		work_dir.push("tests");

		cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).current_dir(work_dir);

		Self {
			raw: cmd,
			run: false,
			stdin: Vec::new(),
			stdout: String::new(),
			stderr: String::new(),
		}
	}

	pub fn env(&mut self, key: &str, val: &str) -> &mut Self {
		self.raw.env(key, val);
		self
	}

	pub fn same_envs(&mut self) -> &mut Self {
		self.raw.envs(env::vars());
		self
	}

	pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Self {
		self.raw.arg(arg);
		self
	}

	pub fn args<I, S>(&mut self, args: I) -> &mut Self
	where
		I: IntoIterator<Item = S>,
		S: AsRef<OsStr>,
	{
		self.raw.args(args);
		self
	}

	pub fn pipe_in(&mut self, filename: &str) -> &mut Self {
		let file = File::open(filename).unwrap();
		self.raw.stdin(Stdio::from(file));
		self
	}

	pub fn pipe_out(&mut self, filename: &str) -> &mut Self {
		let file = File::create(filename).unwrap();
		self.raw.stdout(Stdio::from(file));
		self
	}

	pub fn run(&mut self) -> ExitStatus {
		let mut child = self.raw.spawn().expect("failed to run command");

		if !self.stdin.is_empty() {
			let stdin = child.stdin.as_mut().expect("failed to open stdin");
			stdin.write_all(&self.stdin).expect("failed to write to stdin");
		}

		let output = child
			.wait_with_output()
			.expect("failed waiting for command to complete");
		self.stdout = String::from_utf8(output.stdout).unwrap();
		self.stderr = String::from_utf8(output.stderr).unwrap();
		self.run = true;
		output.status
	}

	pub fn fails(&mut self) -> &mut Self {
		assert!(!self.run().success(), "expected command to fail");
		self
	}

	pub fn succeeds(&mut self) -> &mut Self {
		let status = self.run();
		assert!(
			status.success(),
			"expected command to succeed, but it failed.\nexit code: {}\nstdout: {}\nstderr:{}\n",
			status.code().unwrap(),
			self.stdout,
			self.stderr,
		);
		self
	}

	pub fn no_stdout(&mut self) -> &mut Self {
		assert!(self.run, "command has not yet been run, use succeeds()/fails()");
		assert!(self.stdout.is_empty(), "expected no stdout, got {}", self.stdout);
		self
	}

	pub fn no_stderr(&mut self) -> &mut Self {
		assert!(self.run, "command has not yet been run, use succeeds()/fails()");
		assert!(self.stderr.is_empty(), "expected no stderr, got {}", self.stderr);
		self
	}

	pub fn stdout_is(&mut self, expected: &str) -> &mut Self {
		assert!(self.run, "command has not yet been run, use succeeds()/fails()");
		assert_eq!(&self.stdout[..], expected, "stdout does not match expected");
		self
	}

	pub fn stderr_is(&mut self, expected: &str) -> &mut Self {
		assert!(self.run, "command has not yet been run, use succeeds()/fails()");
		assert_eq!(&self.stderr[..], expected, "stderr does not match expected");
		self
	}
}

impl Default for CommandUnderTest {
	fn default() -> Self {
		Self::new()
	}
}

pub struct Cleanup;

impl Drop for Cleanup {
	fn drop(&mut self) {
		eprintln!("DROP");
		remove_file(TEMP_LOCATION);
	}
}

impl Cleanup {
	#[must_use]
	pub fn new() -> Self {
		eprintln!("Created!");
		Command::new("mkdir")
			.arg(TEMP_LOCATION)
			.stderr(Stdio::null())
			.spawn()
			.unwrap()
			.wait()
			.unwrap();
		Self {}
	}
}

impl Default for Cleanup {
	fn default() -> Self {
		Self::new()
	}
}

pub fn echo(message: &str, filename: &str) {
	let file = File::create(filename).unwrap();
	let status = Command::new("echo")
		.arg("-n")
		.arg(message)
		.stderr(Stdio::null())
		.stdout(Stdio::from(file))
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.code()
		.unwrap();
	assert_eq!(status, 0);
}

pub fn count_characters(filepath: &str, assert_size: usize) {
	let wc = Command::new("wc")
		.arg("-c")
		.arg(filepath)
		.stderr(Stdio::null())
		.output()
		.unwrap();

	let mut awk = Command::new("awk")
		.arg("{ print $1 }")
		.stdin(Stdio::piped())
		.stderr(Stdio::null())
		.stdout(Stdio::piped())
		.spawn()
		.unwrap();

	{
		let awk_in = awk.stdin.as_mut().unwrap();
		awk_in.write_all(&wc.stdout).unwrap();
	}

	let result = awk.wait_with_output().unwrap();

	assert!(result.status.success());
	let out = String::from_utf8(result.stdout).unwrap();
	assert_eq!(out.trim().parse::<usize>().unwrap(), assert_size);
}