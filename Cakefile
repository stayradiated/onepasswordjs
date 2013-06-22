{exec, spawn} = require 'child_process'

task 'build', 'Build project to bin', ->

  exec 'coffee --compile --output js/ source/', (err, stdout, stderr) ->
    throw err if err
    console.log stdout + stderr

task 'tests', 'Run mocha tests', ->

  terminal = spawn('mocha', ['tests'])

  terminal.stdout.on 'data', (data) -> console.log(data.toString())
  terminal.stderr.on 'data', (data) -> console.log(data.toString())
  terminal.on 'error', (data) -> console.log(data.toString())
  terminal.on 'close', (data) -> console.log(data.toString())
