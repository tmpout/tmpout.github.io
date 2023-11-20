{ pkgs ? import <nixpkgs> {} }:

let
  name = "r3s1stanc3";
  email = "r3s1stanc3@riseup.net";
in

pkgs.mkShell {
  # overwrite git parameters for anonymity
  GIT_AUTHOR_NAME = name;
  GIT_AUTHOR_EMAIL =  email;
  GIT_COMMITTER_NAME = name;
  GIT_COMMITTER_EMAIL = email;
  GIT_COMMIT_GPGSIGN = "false";
}
