<?php
Route::group('admin', function () {
    Route::rule('index', 'admin/Index/index');
})->middleware('auth');
