<?php

namespace App\Http\Middleware;

use Carbon\Carbon;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Laravel\Sanctum\PersonalAccessToken;
use Symfony\Component\HttpFoundation\Response;

class TokenExpiration
{
    public function handle(Request $request, Closure $next): Response
    {
        // Get the token from the request
        $token = $request->bearerToken();
        
        if ($token) {
            $accessToken = PersonalAccessToken::findToken($token);

            if ($accessToken) {
                // Get token creation time
                $tokenCreated = $accessToken->created_at;
                $expiresAt = Carbon::parse($tokenCreated)->addMinutes(60); // Set expiration time

                if (Carbon::now()->gt($expiresAt)) {
                    $accessToken->delete(); // Delete only the expired token
                    return response()->json(['message' => 'Session expired. Please log in again.'], 401);
                }
            }
        }

        return $next($request);
    }
}
