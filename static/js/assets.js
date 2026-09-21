(() => {
  const data = document.getElementById("asset-catalogue");
  if (!data) return;
  const catalogue = JSON.parse(data.textContent);
  const type = document.getElementById("asset-type"), role = document.getElementById("asset-role");
  const family = document.getElementById("os-family"), name = document.getElementById("os-name");
  const fill = (select, values, selected) => {
    select.replaceChildren(new Option("Select", ""));
    values.forEach(value => select.add(new Option(value, value, false, value === selected)));
  };
  const osMap = () => {
    const entry = catalogue[type.value] || {};
    return (entry.os_by_role || {})[role.value] || entry.os || {};
  };
  const updateName = (selected = "") => fill(name, osMap()[family.value] || [], selected);
  const updateFamily = (selectedFamily = "", selectedName = "") => {
    fill(family, Object.keys(osMap()), selectedFamily); updateName(selectedName);
  };
  const updateRole = (selectedRole = "", selectedFamily = "", selectedName = "") => {
    fill(role, (catalogue[type.value] || {}).roles || [], selectedRole); updateFamily(selectedFamily, selectedName);
  };
  type.addEventListener("change", () => updateRole());
  role.addEventListener("change", () => updateFamily());
  family.addEventListener("change", () => updateName());
  updateRole(role.dataset.selected, family.dataset.selected, name.dataset.selected);
})();
