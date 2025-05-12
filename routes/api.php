<?php

use App\Http\Controllers\Api\ScanController;

Route::post('/scan', [ScanController::class, 'scan']);
