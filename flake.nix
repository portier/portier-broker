{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, nixpkgs }:
  let

    inherit (nixpkgs) lib;

    forEachSystem = f: lib.mapAttrs (system: f) nixpkgs.legacyPackages;

    makeBrokerPackage = pkgs: buildType:
      pkgs.darwin.apple_sdk_11_0.rustPlatform.buildRustPackage {
        name = "portier-broker";

        src = ./.;
        cargoLock.lockFile = ./Cargo.lock;

        nativeBuildInputs = [ pkgs.makeWrapper ];
        buildInputs = lib.optional pkgs.stdenv.isDarwin (
          with pkgs.darwin.apple_sdk_11_0.frameworks; [ Security SystemConfiguration ]
        );

        doCheck = true;
        inherit buildType;

        postInstall = ''
          mkdir $out/data
          cp -r ./res ./tmpl ./lang $out/data/
          rm $out/data/lang/*.po

          wrapProgram $out/bin/portier-broker \
            --set-default BROKER_DATA_DIR $out/data
        '';
      };

  in {

    packages = forEachSystem (pkgs: rec {
      default = makeBrokerPackage pkgs "release";
      debug = makeBrokerPackage pkgs "debug";
    });

    devShells = forEachSystem (pkgs: {
      default = pkgs.mkShell.override {
        inherit (pkgs.darwin.apple_sdk_11_0) stdenv;
      } {
        nativeBuildInputs = (with pkgs; [ git cmake cargo-audit cargo-outdated ])
          ++ (with pkgs.rustPackages; [ rustc cargo rustfmt clippy ]);
        buildInputs = self.packages.${pkgs.system}.default.buildInputs;
      };
    });

  };
}
