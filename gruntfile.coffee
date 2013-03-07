module.exports = (grunt) ->

  # Project configuration.
  grunt.initConfig
    watch:
      files: './src/*.coffee'
      tasks: 'coffee'
    coffee:
      glob_to_multiple:
        expand: true
        cwd: './src'
        src: ['*.coffee']
        dest: './js'
        ext: '.js'

  # Load plugins...
  grunt.loadNpmTasks('grunt-contrib-coffee')
  grunt.loadNpmTasks('grunt-contrib-watch')

  # Run tasks
  grunt.registerTask('default', 'coffee') # grunt
  grunt.registerTask('compile', 'coffee') # grunt --compile
  grunt.registerTask('watch', 'watch')    # grunt --watch
