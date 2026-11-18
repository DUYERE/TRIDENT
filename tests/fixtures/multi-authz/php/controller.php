<?php
class DemoController {
  public function index() {
    $this->middleware('auth');
    return view('index');
  }
}
