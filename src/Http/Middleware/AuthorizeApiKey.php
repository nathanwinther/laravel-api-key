<?php

namespace Ejarnutowski\LaravelApiKey\Http\Middleware;

use Closure;
use Ejarnutowski\LaravelApiKey\Models\ApiKey;
use Ejarnutowski\LaravelApiKey\Models\ApiKeyAccessEvent;
use Illuminate\Http\Request;

class AuthorizeApiKey
{
    const AUTH_HEADER = 'X-Authorization';
    const QUERYSTRING_KEY = 'apikey';

    /**
     * Handle the incoming request
     *
     * @param Request $request
     * @param Closure $next
     * @return \Illuminate\Contracts\Routing\ResponseFactory|mixed|\Symfony\Component\HttpFoundation\Response
     */
    public function handle(Request $request, Closure $next)
    {
        $keys = [
          $request->header(self::AUTH_HEADER), // Default
          $request->get(self::QUERYSTRING_KEY), // Fallback
        ];

        foreach ($keys as $key) {
          $apiKey = ApiKey::getByKey($key);

          if ($apiKey instanceof ApiKey) {
              $this->logAccessEvent($request, $apiKey);
              return $next($request);
          }
        }

        return response()->json([
            'success' => false,
            'message' => "Sorry, you're not authorized to do that",
            'errors' => (object)[],
        ], 401);
    }

    /**
     * Log an API key access event
     *
     * @param Request $request
     * @param ApiKey  $apiKey
     */
    protected function logAccessEvent(Request $request, ApiKey $apiKey)
    {
        $event = new ApiKeyAccessEvent;
        $event->api_key_id = $apiKey->id;
        $event->ip_address = $request->ip();
        $event->url        = $request->fullUrl();
        $event->save();
    }
}
