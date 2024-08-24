let
  self = import ./. { pkgs = null; system = null; };
in {
  rustPlatform
, openssl
, gnupg
, pkg-config
, installShellFiles
, buildType ? "release"
, hostPlatform
, buildPlatform
, lib
, cargoLock ? crate.cargoLock
, source ? crate.src
, crate ? self.lib.crate
}: rustPlatform.buildRustPackage rec {
  pname = crate.name;
  inherit (crate) version;

  src = source;
  inherit cargoLock buildType;

  buildInputs = lib.optionals hostPlatform.isUnix [
    openssl
    gnupg
  ];
  nativeBuildInputs = [
    installShellFiles
  ] ++ lib.optional hostPlatform.isUnix pkg-config;

  postInstall = ''
    install -Dm755 -t $out/bin bin/git-credential-rbw
  '' + lib.optionalString (buildPlatform.canExecute hostPlatform) ''
    installShellCompletion --cmd rbw \
      --bash <($out/bin/rbw gen-completions bash) \
      --fish <($out/bin/rbw gen-completions fish) \
      --zsh <($out/bin/rbw gen-completions zsh)
  '';

  cargoBuildFlags = [ "--bins" ];
  doCheck = buildType != "release";

  meta = with lib; {
    description = "Unofficial command line client for Bitwarden";
    license = lib.licenses.mit;
    platforms = platforms.unix ++ platforms.windows;
    mainProgram = "rbw";
  };
}
