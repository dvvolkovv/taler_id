import { PartialType } from '@nestjs/mapped-types';
import { RegisterClientDto } from './register-client.dto';

export class UpdateClientDto extends PartialType(RegisterClientDto) {}
