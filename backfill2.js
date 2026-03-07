const { PrismaClient } = require("@prisma/client");
const p = new PrismaClient();
(async () => {
  // Find Dmitry's user ID
  const user = await p.user.findFirst({ where: { email: { contains: "dmitry" } }, select: { id: true, email: true, firstName: true } });
  if (!user) {
    // Try all users
    const users = await p.user.findMany({ select: { id: true, email: true, firstName: true }, take: 5 });
    console.log("Users:", JSON.stringify(users));
    await p.$disconnect();
    return;
  }
  console.log("User:", user);
  
  // Update all summaries that have empty participantIds
  const result = await p.meetingSummary.updateMany({
    where: { participantIds: { isEmpty: true } },
    data: { participantIds: { set: [user.id] } },
  });
  console.log("Updated", result.count, "summaries with userId", user.id);
  await p.$disconnect();
})();
