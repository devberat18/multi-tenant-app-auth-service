import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  async onModuleInit() {
    await this.$connect(); // Uygulama açılırken DB'ye bağlan
  }

  async onModuleDestroy() {
    await this.$disconnect(); // Uygulama kapanırken connection'ı kapat
  }
}