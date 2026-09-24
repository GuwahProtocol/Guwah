import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["scripts/demo*.ts"],
    fileParallelism: false,
    reporters: ["verbose"],
  },
});
