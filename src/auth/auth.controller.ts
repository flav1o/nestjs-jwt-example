import { Body, Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';

@Controller('auth')
export class AuthController {

    constructor(private _authService: AuthService) { }

    @Post('/signup')
    async signUser(@Body() AuthCredentialsDto: AuthCredentialsDto): Promise<void> {
        this._authService.signUp(AuthCredentialsDto);
    }

    @Post('/signin')
    async signIn(@Body() AuthCredentialsDto: AuthCredentialsDto): Promise<{ accessToken }> {
        console.log(AuthCredentialsDto);
        return this._authService.signIn(AuthCredentialsDto);
    }

}
