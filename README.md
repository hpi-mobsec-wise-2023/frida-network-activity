# Frida Network Activity

## How to compile & load

```sh
$ npm install
$ frida -U -f com.example.android --no-pause -l _tracker.js
```

## Development workflow

To continuously recompile on change, keep this running in a terminal:

```sh
$ npm run watch
```

And use an editor like Visual Studio Code for code completion and instant
type-checking feedback.
