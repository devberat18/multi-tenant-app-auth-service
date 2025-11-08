import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModuleModule } from './config-module/config-module.module';

@Module({
  imports: [ConfigModuleModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
