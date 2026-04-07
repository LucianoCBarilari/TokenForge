using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Infrastructure.DataAccess.Migrations
{
    /// <inheritdoc />
    public partial class AddLoginPerformanceIndexes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_LoginAttempts_UserId",
                table: "LoginAttempts");

            migrationBuilder.CreateIndex(
                name: "IX_Users_UserAccount",
                table: "Users",
                column: "UserAccount",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_UserId_LastAttemptAt",
                table: "LoginAttempts",
                columns: new[] { "UserId", "LastAttemptAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Users_UserAccount",
                table: "Users");

            migrationBuilder.DropIndex(
                name: "IX_LoginAttempts_UserId_LastAttemptAt",
                table: "LoginAttempts");

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_UserId",
                table: "LoginAttempts",
                column: "UserId");
        }
    }
}
