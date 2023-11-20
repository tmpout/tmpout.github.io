#!/usr/bin/env bash

shopt -s globstar nullglob
for f in ./**/*.jar
do
  if unzip -l "${f}" | grep -q -F 'doesthislookinfected?';
  then
    echo "${f}"
  fi;
done
