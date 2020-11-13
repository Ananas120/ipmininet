#!/bin/sh

box () {
    printf "\n\e[1;31;40m@@@ $1\e[0m\n\n"
}

box "Executing tests"
sudo py.test || exit 1

box "Packaging the source"
python setup.py sdist || exit 1

if [ "$1" = "push" ]; then
    box "Uploading to Pypi"
    twine upload dist/*
else
    box "Uploading to TestPypi"
    twine upload dist/* -r testpypi
fi
rm -r dist
