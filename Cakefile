{exec} = require 'child_process'
task 'build', 'Build project to bin', ->
  exec 'coffee --compile --output js/ src/', (err, stdout, stderr) ->
    throw err if err
    console.log stdout + stderr
