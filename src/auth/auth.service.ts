import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';
import { UsersRepository } from './users.repository';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './jwt-payload.interface';

@Injectable()
export class AuthService {

    constructor(
        @InjectRepository(UsersRepository)
        private usersRepository: UsersRepository,
        private jwtService: JwtService
    ) { }

    async signUp(AuthCredentialsDto: AuthCredentialsDto): Promise<void> {
        return this.usersRepository.createNewUser(AuthCredentialsDto);
    }

    async signIn(AuthCredentialsDto: AuthCredentialsDto): Promise<{ accessToken }> {
        const { username, password } = AuthCredentialsDto;
        const user = await this.usersRepository.findOne({ username });
        const passwordSuccess = await bcrypt.compare(password, user.password);

        if (user && passwordSuccess) {
            const payload: JwtPayload = { username };
            const accessToken: string = await this.jwtService.sign(payload);
            
            return { accessToken }
        }

        throw new UnauthorizedException('Please check your login information');
    }

}
