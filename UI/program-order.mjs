// One order for every program list: programs that need review first, then the
// most active. Programs with equal counts keep the order they arrived in.
export function orderPrograms(programs) {
  return [...programs].sort((a, b) =>
    Number(b.review?.status === 'attention') - Number(a.review?.status === 'attention') || b.records - a.records);
}
