using Microsoft.EntityFrameworkCore;
using TokenForge.Domain.Entities;

namespace TokenForge.Infrastructure.Persistence.DataAccess
{
    public class TokenForgeContext : DbContext
    {
        public TokenForgeContext(DbContextOptions<TokenForgeContext> options) : base(options) { }
        public virtual DbSet<User> Users { get; set; }
        public virtual DbSet<Role> Roles { get; set; }
        public virtual DbSet<UserRole> UserRoles { get; set; }
        public virtual DbSet<RefreshToken> RefreshTokens { get; set; }
        public virtual DbSet<LoginAttempt> LoginAttempts { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>(entity =>
            {
                entity.HasKey(u => u.UsersId);
                entity.HasIndex(u => u.Email).IsUnique();
                entity.Property(u => u.Email).IsRequired().HasMaxLength(256);
                entity.Property(u => u.UserAccount).IsRequired().HasMaxLength(100);
                entity.Property(u => u.PasswordHash).IsRequired();
                entity.Property(u => u.IsActive).IsRequired();
                entity.Property(u => u.CreatedAt).IsRequired();
                entity.Property(u => u.UpdatedAt);

                entity.HasMany(u => u.RefreshTokens)
                      .WithOne(rt => rt.User)
                      .HasForeignKey(rt => rt.UserId)
                      .OnDelete(DeleteBehavior.Cascade);
            });

            modelBuilder.Entity<Role>(entity =>
            {
                entity.HasKey(r => r.RolesId);
                entity.Property(r => r.RoleName).IsRequired().HasMaxLength(100);
                entity.Property(r => r.RoleDescription).HasMaxLength(256);
                entity.Property(r => r.IsActive).IsRequired();
                entity.Property(r => r.CreatedAt).IsRequired();
                entity.Property(r => r.RevokedAt);
            });

            modelBuilder.Entity<UserRole>(entity =>
            {
                entity.HasKey(ur => ur.UserRoleId);
                entity.Property(ur => ur.AssignedAt).IsRequired();
                entity.Property(ur => ur.IsActive).IsRequired();
                entity.Property(ur => ur.DeactivatedAt);
                entity.Property(ur => ur.DeactivatedReason);

                entity.HasOne(ur => ur.User)
                      .WithMany(u => u.UserRoles)
                      .HasForeignKey(ur => ur.UserId);

                entity.HasOne(ur => ur.Role)
                      .WithMany(r => r.UserRoles)
                      .HasForeignKey(ur => ur.RoleId);
            });

            modelBuilder.Entity<RefreshToken>(entity =>
            {
                entity.HasKey(rt => rt.RefreshTokensId);
                entity.Property(rt => rt.Token).IsRequired();
                entity.HasIndex(rt => rt.Token).IsUnique();
                entity.Property(rt => rt.ExpiresAt).IsRequired();
                entity.Property(rt => rt.CreatedAt).IsRequired();
                entity.Property(rt => rt.RevokedAt);
                entity.Property(rt => rt.ReplacedByToken).HasMaxLength(512);
                entity.Property(rt => rt.IPAddress).HasMaxLength(45);
                entity.Property(rt => rt.UserAgent).HasMaxLength(256);

                entity.HasOne(rt => rt.User)
                      .WithMany(u => u.RefreshTokens)
                      .HasForeignKey(rt => rt.UserId)
                      .IsRequired();
            });

            modelBuilder.Entity<LoginAttempt>(entity =>
            {
                entity.HasKey(la => la.LoginAttemptID);
                entity.Property(la => la.UserAttempt).IsRequired().HasMaxLength(100);
                entity.HasIndex(la => la.UserAttempt);
                entity.Property(la => la.UserId).IsRequired();
                entity.Property(la => la.FailedAttempts).IsRequired();
                entity.Property(la => la.LastAttemptAt).IsRequired();
                entity.Property(la => la.LockedUntil);

                entity.HasOne(la => la.User)
                      .WithMany()
                      .HasForeignKey(la => la.UserId)
                      .OnDelete(DeleteBehavior.Restrict);
            });
            base.OnModelCreating(modelBuilder);
        }
    }
}


