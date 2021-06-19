const fs = require("fs");
const childProcess = require("child_process");

if (process.arch !== "x64" || process.platform !== "linux") {
  throw Error(`Unsupported host: ${process.arch} ${process.platform}`);
}
const NATIVE_TRIPLE = "x86_64-unknown-linux-gnu";

const TARGET_TRIPLE_TO_DEBIAN_ARCH = {
  "aarch64-unknown-linux-gnu": "arm64",
  "arm-unknown-linux-gnueabihf": "armhf",
  "armv7-unknown-linux-gnueabihf": "armhf",
  "i686-unknown-linux-gnu": "i386",
  "mips64el-unknown-linux-gnuabi64": "mips64el",
  "powerpc64le-unknown-linux-gnu": "ppc64el",
  "s390x-unknown-linux-gnu": "s390x",
  "x86_64-unknown-linux-gnu": "amd64",
};

function hasProp(obj, name) {
  return Object.prototype.hasOwnProperty.call(obj, name);
}

function getInputSet(name) {
  return new Set(
    (process.env[`INPUT_${name.toUpperCase()}`] || "")
      .split(/\s+/g)
      .filter((x) => x)
  );
}

function exec(file, args) {
  childProcess.execFileSync(file, args, {
    stdio: ["ignore", "inherit", "inherit"],
  });
}

function main() {
  const targets = getInputSet("targets");
  const packages = getInputSet("packages");

  // Provides crt1.o
  packages.add("libc6-dev");

  const dpkgArchs = new Set();
  const aptPackages = new Set([
    "gcc",
    "pkg-config",
    // Required for the Debian pkg-config cross wrapper.
    "dpkg-dev",
  ]);
  let bashCases = "";

  for (const target of targets) {
    if (!hasProp(TARGET_TRIPLE_TO_DEBIAN_ARCH, target)) {
      throw Error(`Unsupported target: ${target}`);
    }

    const debianArch = TARGET_TRIPLE_TO_DEBIAN_ARCH[target];

    // Derive the GCC target name.
    const gccTarget = target
      // Assumption: all our supported targets have vendor 'unknown'.
      .replace("-unknown", "")
      // ARM is not versioned in the GCC triple.
      .replace(/armv\d+/g, "arm")
      // Dashes only.
      .replace(/_/g, "-");

    if (target === NATIVE_TRIPLE) {
      bashCases += `
        ${target})
          echo -n > ~/.cargo/config
          export -n PKG_CONFIG
          ;;
      `;
    } else {
      dpkgArchs.add(debianArch);
      aptPackages.add(`gcc-${gccTarget}`);
      bashCases += `
        ${target})
          echo "[target.'${target}']" > ~/.cargo/config
          echo "linker = '${gccTarget}-gcc'" >> ~/.cargo/config
          export PKG_CONFIG="${gccTarget}-pkg-config"
          ;;
      `;
    }

    for (const pkg of packages) {
      aptPackages.add(`${pkg}:${debianArch}`);
    }
  }

  for (const arch of dpkgArchs) {
    exec("dpkg", ["--add-architecture", arch]);
  }

  exec("apt-get", ["update", "-y"]);
  exec("apt-get", ["install", "-y", "--no-install-recommends", ...aptPackages]);

  const bashScript = `
    prep_cross() {
      mkdir -p ~/.cargo
      case $1 in
        ${bashCases}
        *)
          echo >&2 "Invalid target: $1"
          exit 1
          ;;
      esac
    }
  `;
  fs.writeFileSync("/tmp/prep_cross.sh", bashScript);
}

try {
  main();
} catch (err) {
  process.exitCode = 1;
  console.log(`::error::${err.message}`);
}
