import { ForbiddenException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { SignInDto, SignUpDto } from './dto';
import { PrismaService } from 'src/prisma/prisma.service';
import * as argon from "argon2"
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {

    constructor(private prisma: PrismaService, private config: ConfigService, private jwt: JwtService) { }

    async signup(dto: SignUpDto) {
        try {
            const hash = await argon.hash(dto.password)
            dto.password = hash
            const user = await this.prisma.user.create({
                data: dto
            })
            delete user.password;
            return user
        } catch (error) {
            if (error instanceof PrismaClientKnownRequestError) {
                if (error.code === 'P2002') throw new ForbiddenException('Credentials taken')
            }
            throw error
        }
    }

    async signin(dto: SignInDto) {
        try {
            const user = await this.prisma.user.findUnique({
                where: {
                    email: dto.email
                }
            })

            if (!user) throw new NotFoundException("Credentials don't exist")

            const pwdMatches = await argon.verify(user.password, dto.password)
            if (!pwdMatches) throw new UnauthorizedException("Credentials incorrects")

            return this.generateJwt(user.id, user.email)
        } catch (error) {
            if (error instanceof PrismaClientKnownRequestError) {
                if (error.code === 'P2002') throw new ForbiddenException('Credentials taken')
            }
            throw error
        }
    }

    async generateJwt(id: number, email: string) {
        const payload = {
            sub: id,
            email: email
        }
        const secret = this.config.get('JWT_SECRET')
        const token = await this.jwt.signAsync(payload, {
            expiresIn: "1d",
            secret: secret
        })

        return {
            access_token: token
        }
    }

}
