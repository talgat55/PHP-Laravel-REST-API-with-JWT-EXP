<?php

namespace App\Http\Controllers;

use JWTAuth;
use App\User;
use Illuminate\Http\Request;
use App\Http\Requests\RegisterAuthRequest;
use Tymon\JWTAuth\Exceptions\JWTException;
use Symfony\Component\HttpFoundation\Response;

class ApiController extends Controller
{
    public $loginAfterSignUp = true;

    /**
     * @param RegisterAuthRequest $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(RegisterAuthRequest $request)
    {
        $user = new User();
        $user->name = $request->name;
        $user->email = $request->email;
        $user->password = bcrypt($request->password);
        $user->save();

        if ($this->loginAfterSignUp) {
            return $this->login($request);
        }
    }

    /**
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $input = $request->only('email', 'password');
        $jwt_token = null;

        if(!$jwt_token = JWTAuth::attempt($input)){
            return response() ->json([
               'successs' => false,
                'message' => 'Invalid Email or Password'
            ], Response::HTTP_UNAUTHORIZED);
        }

        return response()->json([
           'success' => true,
           'token' =>  $jwt_token
        ]);
    }

    /**
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     * @throws \Illuminate\Validation\ValidationException
     */
    public function logout(Request $request){
        $this->validate($request,[
           'token' => 'required'
        ]);

        try {
            JWTAuth::invalidate($request->token);
            return response()->json([
               'success' => true,
               'message' => 'User logged out successfully'
            ]);


        }catch (JWTException $e){
            return response()->json([
                'success' => false,
                'message' => 'Sorry, the user cannot be logged out'
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

    }

    /**
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     * @throws \Illuminate\Validation\ValidationException
     */
    public function getAuthUser(Request $request){
        $this->validate($request, [
           'token' => 'required'
        ]);

        $user = JWTAuth::authentication($request->token);

        return response()->json(['user'=>$user]);
    }

}
