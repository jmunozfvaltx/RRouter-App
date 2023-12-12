/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './devices/templates/**/*.html',
    './templates/**/*.html',
    './node_modules/flowbite/**/*.js'
  ],
  theme: {
    extend: {},
  },
  plugins: [
        require('flowbite/plugin')
    ]
}
