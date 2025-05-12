{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { nixpkgs, ... }:
    let

      inherit (nixpkgs) lib;

      package =
        { lib
        , stdenv
        , rustPlatform
        , cmake
        , makeWrapper
        , buildType ? "release"
        }:
        rustPlatform.buildRustPackage {
          name = "portier-broker";

          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          nativeBuildInputs = [ cmake makeWrapper ];

          doCheck = true;
          inherit buildType;

          # On Linux, release builds fail without this on a memcpy.
          hardeningDisable = [ "strictoverflow" ];

          postInstall = ''
            mkdir $out/data
            cp -r ./res ./tmpl ./lang $out/data/
            rm $out/data/lang/*.po

            wrapProgram $out/bin/portier-broker \
              --set-default BROKER_DATA_DIR $out/data
          '';
        };

      overlay = final: prev: {
        portier-broker = final.callPackage package { };
      };

      pkgs = lib.listToAttrs (map
        (system: {
          name = system;
          value = import nixpkgs {
            inherit system;
            overlays = [ overlay ];
          };
        })
        [
          "x86_64-linux"
          "aarch64-linux"
          "x86_64-darwin"
          "aarch64-darwin"
        ]);

      forEachSystem = f: lib.mapAttrs (system: f) pkgs;

    in
    {

      overlays.default = overlay;

      packages = forEachSystem (pkgs: {
        default = pkgs.portier-broker;
        debug = pkgs.portier-broker.override { buildType = "debug"; };
      });

      devShells = forEachSystem (pkgs: {
        default = pkgs.mkShell.override
          { inherit (pkgs.portier-broker) stdenv; }
          {
            nativeBuildInputs = pkgs.portier-broker.nativeBuildInputs
              ++ (with pkgs; [ git cargo-audit cargo-outdated ])
              ++ (with pkgs.rustPackages; [ rustfmt clippy ]);
            buildInputs = pkgs.portier-broker.buildInputs;
          };
      });

    };
}
