
# Installation and creation of a new Angular 2 project
npm install -g angular-cli
go to a folder and type
ng new Testng
Once finished go inside the Testng folder and type:
ng serve

Open Atom editor and open the Testng folder
Install typescript syntax on Atom as follows:
apm install atom-typescript

# Note on Jquery Installation
First: Install jQuery, the actual library
npm install jquery --save

Then: Install jQuery TypeScript autocomplete
npm install @types/jquery --save-dev

Finally: Go to the ./angular-cli.json file at the root of your Angular CLI project folder, and find the scripts: [] property, add this inside it:
"../node_modules/jquery/dist/jquery.min.js"

After that, jQuery will be available for you as a global variable. You can log jQuery’s version (which is available as jQuery.fn.jquery   or $.fn.jquery) to ensure it’s working brilliantly.


#note on Jwplayer Installation
in order to install Jwplayer first one has to create an account at https://www.jwplayer.com/
then in the dashboard one has to choose tool and get the licence key.

Thenext step is to install the wrapper via npm at https://github.com/bianjp/jwplayer
npm install --save @bianjp/jwplayer

then the typings for typescript:
npm install --save @types/jwplayer

then it is possible to work with Jwplayer

#Add different file type to deployment.
The "assets" property of angular-cli.json can be configured to include custom files in angular-cli webpack build. So, configure "assets" property value as an array. For example:

"assets": [
  "assets",
  "favicon.ico","playList.txt"
],


# Testng
This project was generated with [angular-cli](https://github.com/angular/angular-cli) version 1.0.0-beta.28.3.

## Development server
Run `ng serve` for a dev server. Navigate to `http://localhost:4200/`. The app will automatically reload if you change any of the source files.

## Code scaffolding

Run `ng generate component component-name` to generate a new component. You can also use `ng generate directive/pipe/service/class/module`.

## Build

Run `ng build` to build the project. The build artifacts will be stored in the `dist/` directory. Use the `-prod` flag for a production build.

## Running unit tests

Run `ng test` to execute the unit tests via [Karma](https://karma-runner.github.io).

## Running end-to-end tests

Run `ng e2e` to execute the end-to-end tests via [Protractor](http://www.protractortest.org/).
Before running the tests make sure you are serving the app via `ng serve`.

## Deploying to GitHub Pages

Run `ng github-pages:deploy` to deploy to GitHub Pages.

## Further help
To get more help on the `angular-cli` use `ng help` or go check out the [Angular-CLI README](https://github.com/angular/angular-cli/blob/master/README.md).
