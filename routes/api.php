<?php

use App\Http\Controllers\Auth\AuthenticatedSessionController;
use App\Http\Controllers\Auth\NewPasswordController;
use App\Http\Controllers\Auth\PasswordController;
use App\Http\Controllers\CommentController;
use App\Http\Controllers\ExternalNewsController;
use App\Http\Controllers\LikeController;
use App\Http\Controllers\NewsController;
use App\Models\ExternalNews;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;



Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');





Route::get('/sanctum/csrf-cookie', [\Laravel\Sanctum\Http\Controllers\CsrfCookieController::class, 'show']);
Route::middleware('auth:sanctum')->get('/user', function () {
    return response()->json([
        'status' => true,
        'user' => Auth::user(),
    ]);
});
Route::get('/test', function () {
    return response()->json(['message' => 'API is working']);
});
Route::get('/logout', function () {
    Auth::logout();
    return response()->json([
        'status' => true,
        'message' => 'Logout successfully',
    ]);
})->middleware('auth:sanctum');


Route::middleware('guest')->group(function () {
    Route::get('reset-password/{token}', [NewPasswordController::class, 'create'])
        ->name('password.reset'); // Ensure this route is defined
    // ... other routes
});

Route::put('password', [PasswordController::class, 'update'])->name('password.update');
// Route::post('forgot-password', [PasswordResetLinkController::class, 'store'])
//         ->name('password.email');

Route::post('/uploadProfilePic',[AuthenticatedSessionController::class, 'uploadPicture']);



Route::middleware(['auth:admin', \App\Http\Middleware\CheckAdminIsHeadAdmin::class])->group(function () {
    Route::get('/admin/news', [NewsController::class, 'index']);
    Route::post('/admin/news', [NewsController::class, 'store']);
    Route::put('/admin/news/{id}', [NewsController::class, 'update']);
    Route::delete('/admin/news/{id}', [NewsController::class, 'destroy']);
});



Route::get('/news', [NewsController::class, 'index']);
Route::post('/news/{newsId}/like', [LikeController::class, 'toggleLike']);
Route::post('/news/{newsId}/comment', [CommentController::class, 'store']);
Route::get('news/{newsId}/comment', [CommentController::class, 'index']);


Route::get('external-news', [ExternalNewsController::class, 'getExternalNews']);

// Route to fetch and store external news from the API
Route::get('fetch-external-news', [ExternalNewsController::class, 'fetchExternalNews']);

require __DIR__.'/auth.php';
require __DIR__.'/admin.php';
