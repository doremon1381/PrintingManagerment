<script setup lang="ts">
import { computed, ref, defineModel, watch, nextTick } from 'vue';
import {
    PencilIcon,
    KeyIcon,
} from 'vue-tabler-icons';
import { mdiDelete, mdiOfficeBuilding, mdiPencil } from '@mdi/js';
import { useAxiosGetWithAccessToken } from '@/extensions/RequestUltilities';

//const authStore = useAuthStore();
const users = ref();

const getUsers = computed(() => { return users.value; });

function serializeUsers(data) : Array<User>
{
    const obj : Array<User> = [];
    data.forEach(element => {
        const n : User = {
            Name: element.Name,
            Username: element.Username,
            Phone: element.Phone,
            Email: element.Email,
            Group: element.Group.split(',').filter((el: string) => { return el != ''; })
        }
        obj.push(n);
    });

    return obj;
}

useAxiosGetWithAccessToken("/users/all", response => {
    users.value = serializeUsers(response.data);
}, () => {});

const editedItem = ref({
    Name:'',
    Email:'',
    Phone:'',
    Group:[''], // Permission    
});

const defaultItem = ref({
    Name:'',
    Email:'',
    Phone:'',
    Group:[''], // Permission    
});

interface User{
    Username: string,
    Name: string;
    Email: string;
    Phone: string;
    Group: Array<string>;
}

const editedIndex = ref(-1);

const dialog = ref(false);
const dialogDelete = ref(false);

watch(dialog, (newVal: boolean) => {
    newVal || close();
});
watch(dialogDelete, (newVal:boolean) => {
    newVal || closeDelete();
});

function editUserGroup (item: User) {
    editedIndex.value = getUsers.value.indexOf(item)
    editedItem.value = Object.assign({}, item)
    dialog.value = true
};

function editUserTeam(item: User)
{

}

function deleteItem (item) {
    editedIndex.value = getUsers.value.indexOf(item)
    editedItem.value = Object.assign({}, item)
    dialogDelete.value = true
};

function close () {
    dialog.value = false
    nextTick(() => {
        editedItem.value = Object.assign({}, defaultItem.value)
        editedIndex.value = -1
    })
};
function closeDelete () {
    dialogDelete.value = false
    nextTick(() => {
        editedItem.value = Object.assign({}, defaultItem.value);
        editedIndex.value = -1;
    })
};

function save () {
    if (editedIndex.value > -1) {
        Object.assign(getUsers.value[editedIndex], editedItem.value)
    } else {
        getUsers.value.push(editedItem.value)
    }
    close()
};

const headers = ref([{
    title: 'Họ và tên',
    value: 'Name'
}, {
    title: 'UserName',
    value: "Username"
}, {
    title: 'Số điện thoại',
    value: 'Phone'
}, {
    title: 'Nhóm',
    value: 'Group',
    key: 'group'
}, {
    title: 'Actions',
    key:'actions',
    sortable: false
}]);

</script>

<template>
    <div>
      <v-data-table
            :headers="headers"
            :items="getUsers"
        >
        <template v-slot:item.group="{ item }">
                <div class="text-start" >
                    <v-chip v-for="g in item.Group" :key="g"
                        :color="g ? 'green' : 'red'"
                        :text="g"
                        class="text-uppercase"
                        size="small"
                        label
                    ></v-chip>
                    </div>
            </template>
            <template v-slot:item.actions="{ item }">
                <v-icon class="me-2" size="small" @click="editUserTeam" :icon="mdiOfficeBuilding"></v-icon>
                <v-icon
                    class="me-2"
                    size="small"
                    @click="editUserGroup(item)"
                    :icon="mdiPencil">                           
                </v-icon>
                <v-icon
                    size="small"
                    @click="deleteItem(item)"
                    :icon="mdiDelete">                    
                </v-icon>
            </template>
        </v-data-table>
    </div>
</template>