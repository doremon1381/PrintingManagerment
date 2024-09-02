<script setup lang="ts">
import { computed, ref, defineModel, watch, nextTick } from 'vue';
import { mdiDelete, mdiOfficeBuilding, mdiPencil } from '@mdi/js';
import { useAxiosGetWithAccessToken } from '@/extensions/RequestUltilities';
import { useAuthStore } from '@/stores/auth';
import { mdiMagnify } from '@mdi/js';

const authStore = useAuthStore();
const users = ref();

const getUsers = computed(() : Array<User> => { return users.value; });
const currentUsername = computed(() => { return authStore.user?.sub; });

function serializeUsers(data) : Array<User>
{
    const obj : Array<User> = [];
    data.forEach(element => {
        const n : User = {
            Name: element.Name,
            Username: element.Username,
            Phone: element.Phone,
            Email: element.Email,
            Group: element.Group,
            Roles: element.Roles?.split(',').filter((el: string) => { return el != ''; }),
            IsModified: false,
            IsDeleted: false,
            IsAdmin: element.Roles.includes('admin') ? true : false
        }
        obj.push(n);
    });

    return obj;
}

useAxiosGetWithAccessToken("/users/all", response => {
    users.value = serializeUsers(response.data);
    drafUsers.value = serializeUsers(response.data);
    nextTick();

    isLoading.value = false;
}, () => {});

const drafUsers = ref();

const editedItem = ref({
    Username:'',
    Name:'',
    Email:'',
    Phone:'',
    Roles:[''],
    Group:'', // Permission
    IsModified:false,
    IsDeleted:false
});

const defaultItem = ref({
    Username:'',
    Name:'',
    Email:'',
    Phone:'',
    Roles:[''],
    Group:'', // Permission    
    IsModified:false,
    IsDeleted:false
});

const isLoading = ref(true);
const search = ref('');
const page = ref(1);
const itemPerPage = ref(7);

const pageCount = computed(() : number => {
    return Math.ceil(getUsers.value.length / itemPerPage.value);
})

interface User{
    Username: string,
    Name: string;
    Email: string;
    Phone: string;
    Roles: Array<string>;
    Group: string;
    IsModified:boolean;
    IsDeleted:boolean;
    IsAdmin?:boolean
}

//type Roles = "admin"|"employee"|"designer"|"deliver"|"manager"|"leader";

const roles = ['admin', 'employee', 'designer', 'deliver', 'manager','leader'];

const editedIndex = ref(-1);

const dialog = ref(false);
const dialogDelete = ref(false);

watch(dialog, (newVal: boolean) => {
    newVal || close();
});
watch(dialogDelete, (newVal:boolean) => {
    newVal || closeDelete();
});

const editedItemDefaultSelected = ref(['']);

function editUserGroup (item: User) {
    editedIndex.value = getUsers.value.indexOf(item);
    editedItem.value  = getUsers.value[editedIndex.value];
    editedItemDefaultSelected.value = editedItem.value.Roles;

    //console.log(editedItemDefaultSelected.value);    
    dialog.value = true
};

function editUserTeam(item: User)
{

}

function close () {
    dialog.value = false;
    nextTick(() => {
        editedItem.value = Object.assign({}, defaultItem.value);
        editedIndex.value = -1;
        //editedItemDefaultSelected.value = [''];
    })
};

function save () {
    if (editedIndex.value > -1) {
        //var currentRoles = getUsers.value[editedIndex.value].Roles;
        getUsers.value[editedIndex.value].Roles = editedItemDefaultSelected.value;
        const userBaseRoles = drafUsers.value[editedIndex.value].Roles;
        var currentRoles = getUsers.value[editedIndex.value].Roles;

        function hasEqualValue(val: string){
            let isEquals = false;
            currentRoles.forEach(element => {
                if (element == val){
                    isEquals = true;
                }
            });

            return isEquals;
        }

        if (userBaseRoles.length !== getUsers.value[editedIndex.value].Roles.length){
            getUsers.value[editedIndex.value].IsModified = true;
        }
        else {
            userBaseRoles.forEach(element => {
                getUsers.value[editedIndex.value].IsModified = !hasEqualValue(element);
            });
        }

        if (!getUsers.value[editedIndex.value].Roles.includes('admin'))
            getUsers.value[editedIndex.value].IsAdmin = false;
    } else {
        //getUsers.value.push(editedItem.value)
    }
    close()
};

function deleteItem (item: User) {
    editedIndex.value = getUsers.value.indexOf(item)
    editedItem.value = Object.assign({}, item)
    dialogDelete.value = true
};

function closeDelete () {
    dialogDelete.value = false
    nextTick(() => {
        editedItem.value = Object.assign({}, defaultItem.value);
        editedIndex.value = -1;
    })
};
function deleteItemConfirm () {
    getUsers.value.splice(editedIndex.value, 1);
    closeDelete()
};

const headers = ref([{
    title: 'Họ và tên',
    value: 'Name',
    filterable: true
}, {
    title: 'UserName',
    value: "Username",
    filterable: false
}, {
    title: 'Số điện thoại',
    value: 'Phone',
    filterable: false
}, {
    title: 'Nhóm',
    value: 'Group',
    key: 'group',
    filterable: false
},{
    title: 'Roles',
    value: 'Roles',
    key: 'roles',
    filterable: false
}, {
    title: 'Actions',
    key:'actions',
    sortable: false,
    filterable: false
}]);

</script>

<template>
    <div>
        <v-progress-linear color="cyan" indeterminate v-if="isLoading"></v-progress-linear>
        <v-card v-else flat>
            <template v-slot:text>
                <v-text-field
                    v-model="search"
                    label="Search by name"
                    :prepend-inner-icon="mdiMagnify"
                    variant="outlined"
                    hide-details
                    single-line
                ></v-text-field>
            </template>
            <v-data-table
            :headers="headers"
            :search="search"
            :items="getUsers"
            :page="page"
            :items-per-page="itemPerPage">
            <template v-slot:top>
                <v-dialog v-model="dialog" max-width="500px">
                    <v-card>
                        <v-card-title>
                            <span class="text-h5">Edit Item</span>
                        </v-card-title>
                        <v-card-text>
                            <v-container>
                                    <v-select :items="roles" v-model="editedItemDefaultSelected" variant="outlined" label="Cập nhật quyền hạn" multiple>
                                    </v-select>
                            </v-container>
                        </v-card-text>

                        <v-card-actions>
                        <v-spacer></v-spacer>
                        <v-btn
                            color="blue-darken-1"
                            variant="text"
                            @click="close"
                        >
                            Cancel
                        </v-btn>
                        <v-btn
                            color="blue-darken-1"
                            variant="text"
                            @click="save"
                        >
                            Save
                        </v-btn>
                        </v-card-actions>
                    </v-card>
                </v-dialog>
                <v-dialog v-model="dialogDelete" max-width="500px">
                    <v-card>
                        <v-card-title class="text-h5">Are you sure you want to delete this item?</v-card-title>
                        <v-card-actions>
                        <v-spacer></v-spacer>
                        <v-btn color="blue-darken-1" variant="text" @click="closeDelete">Cancel</v-btn>
                        <v-btn color="blue-darken-1" variant="text" @click="deleteItemConfirm">OK</v-btn>
                        <v-spacer></v-spacer>
                        </v-card-actions>
                    </v-card>
                </v-dialog>
            </template>
            <template v-slot:item.group="{ item }">
                    <div class="text-start" >
                        <v-chip 
                            :color="item.Group ? 'success' : 'primary'"
                            :text="item.Group"
                            class="text-uppercase"
                            size="small"
                            label
                        ></v-chip>
                        </div>
            </template>
            <template v-slot:item.roles="{ item }">
                    <div class="text-start" >
                        <v-chip v-for="g in item.Roles" :key="g"
                            :color="g ? 'success' : 'primary'"
                            :text="g"
                            class="text-uppercase ma-1"
                            size="small"
                            label
                        ></v-chip>
                    </div>
            </template>
            <template v-slot:item.actions="{ item }">
                <v-icon class="me-2" size="small" @click="editUserTeam" :icon="mdiOfficeBuilding" title="Cập nhật phòng ban nhân viên"></v-icon>
                <v-icon
                    class="me-2"
                    size="small"
                    @click="editUserGroup(item)"
                    title="Cập nhật quyền hạn"
                    :disabled="item.IsAdmin && !item.Username.includes(currentUsername)"
                    :icon="mdiPencil">
                </v-icon>
                <v-icon
                    size="small"
                    @click="deleteItem(item)"
                    title="Xóa nhân viên"
                    :disabled="item.IsAdmin"
                    :icon="mdiDelete">                    
                </v-icon>
            </template>
            <template v-slot:bottom>
                <div class="text-center pt-2">
                    <v-pagination
                    v-model="page"
                    :length="pageCount"
                    ></v-pagination>
                </div>
            </template>
        </v-data-table>
        </v-card>
        
    </div>
</template>