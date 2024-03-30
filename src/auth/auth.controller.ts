import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { User } from './decorators';
import { SignInDto, SignUpDto } from './dto';

@Controller('auth')
export class AuthController {

    constructor(private authService: AuthService) { }

    @HttpCode(HttpStatus.OK)
    @Post("signin")
    signin(@Body() dto: SignInDto) {
        return this.authService.signin(dto)
    }

    @Post("signup")
    signup(@Body() dto: SignUpDto) {
        console.log(dto);
        return this.authService.signup(dto)
    }
}
