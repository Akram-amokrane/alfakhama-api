import { IsAlpha, IsEmail, IsNotEmpty, IsString, IsStrongPassword, Length } from "class-validator";

export class SignUpDto {
    @IsString()
    @IsAlpha()
    @IsNotEmpty()
    firstName: string;
    @IsString()
    @IsAlpha()
    @IsNotEmpty()
    lastName: string;

    @IsEmail()
    @IsNotEmpty()
    email: string;

    @IsString()
    @IsNotEmpty()
    @Length(8)
    password: string;

}

export class SignInDto {
    @IsEmail()
    @IsNotEmpty()
    email: string;

    @IsString()
    @IsNotEmpty()
    @Length(8)
    password: string;
}