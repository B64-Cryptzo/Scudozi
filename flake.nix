{
  description = "Scudozi - self-hosted security visibility with reproducible Nix deployment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        version = "0.1.0";
        scudozi = pkgs.buildGoModule {
          pname = "scudozi";
          inherit version;
          src = self;
          vendorHash = null;
          subPackages = [ "." ];
          nativeBuildInputs = [ pkgs.makeWrapper ];
          postInstall = ''
            mkdir -p $out/share/scudozi
            cp -r ${self}/site $out/share/scudozi/site
            wrapProgram $out/bin/scudozi \
              --set-default SCUDOZI_SITE_DIR $out/share/scudozi/site \
              --set-default SCUDOZI_CREDS_FILE /tmp/scudozi-demo-creds.txt
          '';
        };
      in
      {
        packages.default = scudozi;
        packages.scudozi = scudozi;

        apps.default = {
          type = "app";
          program = "${scudozi}/bin/scudozi";
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            go
            gopls
            delve
            gotools
            nixpkgs-fmt
          ];
          shellHook = ''
            echo "Scudozi dev shell ready."
            echo "Run: go run ."
          '';
        };
      })
    // {
      nixosModules.default = import ./nix/module.nix;
      nixosModules.scudozi = import ./nix/module.nix;
    };
}

