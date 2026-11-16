// One order for every program list: threats first, then unresolved programs,
// then the most active. Programs with equal counts keep the order they arrived in.
export function orderPrograms(programs) {
  const rank = program => ['attention', 'threat'].indexOf(program.review?.status);
  return [...programs].sort((a, b) => rank(b) - rank(a) || b.records - a.records);
}
