<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create(config('bherila-auth.passkeys.table', 'auth_passkeys'), function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('credential_id', 2048)->unique();
            $table->text('public_key');
            $table->unsignedBigInteger('counter')->default(0);
            $table->string('aaguid', 64)->nullable();
            $table->string('name')->default('Passkey');
            $table->json('transports')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();
            $table->index('user_id');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists(config('bherila-auth.passkeys.table', 'auth_passkeys'));
    }
};
