// Component
import { Component,AfterViewInit } from '@angular/core';
import { FlowerService } from '../../services/flowerservice';

@Component({
  selector: 'app-component', //The entry point
  providers: [FlowerService],
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent implements AfterViewInit {
  constructor(private flowerservice: FlowerService) {}
  //ngOnInit() is called right after the directive's data-bound properties have been checked for the first time,
  // and before any of its children have been checked. It is invoked only once when the directive is instantiated.
  ngOnInit(){}
  //ngAfterViewInit() is called after a component's view, and its children's views, are created.
  // Its a lifecycle hook that is called after a component's view has been fully initialized.(document.ready for the component)
  ngAfterViewInit() {
    this.flowerservice.authenticate().subscribe(data => this.token = data);
    var playerInstance = jwplayer("jwplayercontainer");
    playerInstance.setup({
    "playlist": "playList.txt",   // renamed from json to txt because dmm888.com doesn't like json
    "height": 326,
    "width": 580,
    "key":"G1VjVx3NzbExARB/D0TFxwr4oC3ilweCL/dt3A==",
    "autostart": false});
  }

  title = 'DM88 component';
  jqueryversion = `This site is using Jquery ${$.fn.jquery}`;
  timer={}
  name = 'David';
  counter = 10;
  flowers = [];
  token = {};
  increment() { this.counter++; }
  decrement() { this.counter--; }
  refreshToken() { this.flowerservice.authenticate().subscribe(data => this.token = data); }
  loadFlowers() {
      this.flowerservice.getFlowers().subscribe(data => this.flowers = data);
    }
}
