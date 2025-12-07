/* eslint-disable prettier/prettier */
import { Test, TestingModule } from '@nestjs/testing';
import {
  BadRequestException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';

import { AuthService } from './auth.service';
import { AuthDbService } from './auth.db.service';
import { RedisService } from 'src/redis/redis.service';
import { PrismaService } from 'src/prisma/prisma.service';

// ---- MOCKLAR ----
jest.mock('bcrypt');

const mockJwtService = { sign: jest.fn() };
const mockAuthDbService = {
  findOne: jest.fn(),
  findById: jest.fn(),
  createUser: jest.fn(),
  updateLastLogin: jest.fn(),
  getPasswordResetByUserAndToken: jest.fn(),
};
const mockRedisService = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  keys: jest.fn(),
};
const mockPrismaService = {
  token: {
    create: jest.fn(),
    findUnique: jest.fn(),
    update: jest.fn(),
    updateMany: jest.fn(),
  },
  user: { update: jest.fn() },
  passwordReset: { update: jest.fn() },
  $transaction: jest.fn().mockResolvedValue(true),
};

describe('AuthService', () => {
  let service: AuthService;

  // ✔ beforeEach en üst seviyedeki describe içinde olacak
  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: JwtService, useValue: mockJwtService },
        { provide: AuthDbService, useValue: mockAuthDbService },
        { provide: RedisService, useValue: mockRedisService },
        { provide: PrismaService, useValue: mockPrismaService },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);

    jest.clearAllMocks();
    (bcrypt.hash as jest.Mock).mockResolvedValue('hashed-value');
  });

  // ------------------------------------------------------------------------
  it('service should be defined', () => {
    expect(service).toBeDefined();
  });
  // ------------------------------------------------------------------------

  describe('login', () => {
    const ip = '127.0.0.1';
    const userAgent = 'jest';

    it('should throw BadRequestException when required fields missing', async () => {
      await expect(
        service.login({} as any, ip, userAgent),
      ).rejects.toBeInstanceOf(BadRequestException);
    });

    it('should throw NotFoundException when user not found', async () => {
      mockAuthDbService.findOne.mockResolvedValue(null);
      await expect(
        service.login(
          { email: 'test@example.com', password: '123456' },
          ip,
          userAgent,
        ),
      ).rejects.toBeInstanceOf(NotFoundException);
    });

    it('should throw UnauthorizedException when password invalid', async () => {
      mockAuthDbService.findOne.mockResolvedValue({
        id: '1',
        password: 'hashed',
      });
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      await expect(
        service.login(
          { email: 'test@example.com', password: 'wrong' },
          ip,
          userAgent,
        ),
      ).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('should login successfully', async () => {
      const fakeUser = {
        id: '1',
        email: 't',
        username: 'u',
        password: 'hashed',
      };

      mockAuthDbService.findOne.mockResolvedValue(fakeUser);
      (bcrypt.compare as jest.Mock).mockResolvedValue(true);
      mockJwtService.sign
        .mockReturnValueOnce('access-token')
        .mockReturnValueOnce('refresh-token');

      mockPrismaService.token.create.mockResolvedValue({
        id: 1,
        userId: '1',
        refreshToken: 'hashed-refresh',
      });

      const result = await service.login(
        { email: 'test@example.com', password: '123456' },
        '127.0.0.1',
        'jest',
      );

      expect(result.accessToken).toBe('access-token');
      expect(result.refreshToken).toBeDefined();
    });
  });

  // ------------------------------------------------------------------------
  describe('register', () => {
    it('should fail when password missing', async () => {
      await expect(
        service.register({
          username: 'b',
          email: 't',
          phone_number: '5',
          password: '',
          rePassword: '',
        }),
      ).rejects.toBeInstanceOf(BadRequestException);
    });

    it('should fail mismatch passwords', async () => {
      await expect(
        service.register({
          username: 'b',
          email: 't',
          phone_number: '5',
          password: '123',
          rePassword: '456',
        }),
      ).rejects.toBeInstanceOf(BadRequestException);
    });

    it('should create user', async () => {
      mockAuthDbService.createUser.mockResolvedValue({ id: '1' });
      (bcrypt.hash as jest.Mock).mockResolvedValue('hashed');

      const result = await service.register({
        username: 'b',
        email: 't',
        phone_number: '5',
        password: '123',
        rePassword: '123',
      });

      expect(result.id).toBe('1');
    });
  });

  // ------------------------------------------------------------------------
  describe('refreshToken', () => {
    it('should fail when redis missing', async () => {
      mockRedisService.get.mockResolvedValue(null);
      await expect(service.refreshToken('abc')).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
    });

    it('should fail when token not found', async () => {
      mockRedisService.get.mockResolvedValue(
        JSON.stringify({ userId: '1', tokenId: 1 }),
      );
      mockPrismaService.token.findUnique.mockResolvedValue(null);
      await expect(service.refreshToken('abc')).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
    });

    it('should fail when hash mismatch', async () => {
      mockRedisService.get.mockResolvedValue(
        JSON.stringify({ userId: '1', tokenId: 1 }),
      );
      mockPrismaService.token.findUnique.mockResolvedValue({
        id: 1,
        refreshToken: 'hashed',
        expiresAt: new Date(Date.now() + 10000),
      });
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      await expect(service.refreshToken('abc')).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
    });
  });

  // ------------------------------------------------------------------------
  describe('passwordReset', () => {
    const ip = '127.0.0.1';
    const userAgent = 'jest';

    it('should fail when redis missing', async () => {
      mockRedisService.get.mockResolvedValue(null);

      await expect(
        service.passwordReset({
          passwordResetToken: 't',
          password: '1',
          rePassword: '1',
          ip,
          userAgent,
        }),
      ).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('should fail when user missing', async () => {
      mockRedisService.get.mockResolvedValue(
        JSON.stringify({ userId: '1', ip, userAgent }),
      );
      mockAuthDbService.findById.mockResolvedValue(null);

      await expect(
        service.passwordReset({
          passwordResetToken: 't',
          password: '1',
          rePassword: '1',
          ip,
          userAgent,
        }),
      ).rejects.toBeInstanceOf(NotFoundException);
    });

    it('should fail when device mismatch', async () => {
      mockRedisService.get.mockResolvedValue(
        JSON.stringify({
          userId: '1',
          ip: '1.1.1.1',
          userAgent: 'wrong',
        }),
      );
      mockAuthDbService.findById.mockResolvedValue({ id: '1' });

      await expect(
        service.passwordReset({
          passwordResetToken: 't',
          password: '1',
          rePassword: '1',
          ip,
          userAgent,
        }),
      ).rejects.toBeInstanceOf(UnauthorizedException);
    });
  });
});
