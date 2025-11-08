import { Module } from '@nestjs/common';
import { ConfigModuleService } from './config-module.service';

@Module({
  providers: [ConfigModuleService]
})
export class ConfigModuleModule {}
