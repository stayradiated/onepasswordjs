{exec, spawn} = require 'child_process'

option '-w', '--watch', 'Watch folder and compile on changes'

task 'build', 'Build project to bin', (options) ->

  cmd = 'coffee'
  args = ['-c', '-o', 'js/', 'source/']
  if options.watch then args.unshift '-w'

  process = spawn(cmd, args)
  process.stdout.on 'data', (data) -> console.log data.toString()
  process.stderr.on 'data', (data) -> console.log data.toString()

task 'tests', 'Run mocha tests', ->

  terminal = spawn('./node_modules/mocha/bin/mocha', ['tests'])
  terminal.stdout.on 'data', (data) -> console.log data.toString()
  terminal.stderr.on 'data', (data) -> console.log data.toString()
