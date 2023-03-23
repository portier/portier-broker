{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, nixpkgs }:
  let

    inherit (nixpkgs) lib;

    forEachSystem = f: lib.mapAttrs (system: f) nixpkgs.legacyPackages;

    makeBrokerPackage = pkgs: buildType:
      with pkgs;
      rustPlatform.buildRustPackage {
        name = "portier-broker";

        src = ./.;
        cargoLock.lockFile = ./Cargo.lock;

        nativeBuildInputs = [ makeWrapper ];
        buildInputs = lib.optional stdenv.isDarwin (
          with darwin.apple_sdk.frameworks; [ Security ]
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
      default = with pkgs; mkShell {
        nativeBuildInputs = [ git cargo-audit cargo-outdated ]
          ++ (with rustPackages; [ rustc cargo rustfmt clippy ]);
        buildInputs = self.packages.${pkgs.system}.default.buildInputs;
      };
    });

  };
}
